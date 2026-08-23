package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"text/template/parse"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/leonelquinteros/gotext"
	"github.com/samber/mo"
)

type Translation struct {
	MsgID       string
	MsgIDPlural mo.Option[string]
	Refs        mapset.Set[string]
}

// Convert a byte position in src to a 1-based line number
func lineForPos(src string, pos parse.Pos) int {
	byteOffset := min(int(pos), len(src))
	return strings.Count(src[:byteOffset], "\n") + 1
}

func extractFromCallCommand(cmd *parse.CommandNode, src, filePath string) []Translation {
	if len(cmd.Args) < 3 {
		return nil
	}
	ident, ok := cmd.Args[0].(*parse.IdentifierNode)
	if !ok || ident.Ident != "call" {
		return nil
	}

	var funcName string
	switch receiver := cmd.Args[1].(type) {
	case *parse.FieldNode:
		if len(receiver.Ident) == 1 {
			funcName = receiver.Ident[0]
		}
	case *parse.VariableNode:
		if len(receiver.Ident) == 2 && receiver.Ident[0] == "$" {
			funcName = receiver.Ident[1]
		}
	case *parse.ChainNode:
		if v, ok := receiver.Node.(*parse.VariableNode); ok && len(v.Ident) == 1 && v.Ident[0] == "$" && len(receiver.Field) == 1 {
			funcName = receiver.Field[0]
		}
	}

	if funcName != "T" && funcName != "TN" {
		return nil
	}

	loc := fmt.Sprintf("%s:%d", filePath, lineForPos(src, cmd.Position()))

	msgidNode, ok := cmd.Args[2].(*parse.StringNode)
	if !ok {
		fmt.Fprintf(os.Stderr, "Warning: %s: T call with non-string-literal msgid, skipping\n", loc)
		return nil
	}

	var msgidPlural mo.Option[string]
	if funcName == "TN" {
		if len(cmd.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Warning: %s: TN call missing plural argument, skipping\n", loc)
			return nil
		}
		pluralNode, ok := cmd.Args[3].(*parse.StringNode)
		if !ok {
			fmt.Fprintf(os.Stderr, "Warning: %s: TN call with non-string-literal msgid_plural, skipping\n", loc)
			return nil
		}
		msgidPlural = mo.Some(pluralNode.Text)
	}

	return []Translation{{
		MsgID:       msgidNode.Text,
		MsgIDPlural: msgidPlural,
		Refs:        mapset.NewSet(loc),
	}}
}

func extractFromNode(node parse.Node, src, filePath string) []Translation {
	switch n := node.(type) {
	case *parse.ListNode:
		return flatMap(n.Nodes, func(child parse.Node) []Translation {
			return extractFromNode(child, src, filePath)
		})

	case *parse.ActionNode:
		return extractFromPipe(n.Pipe, src, filePath)

	case *parse.IfNode:
		return extractFromBranch(&n.BranchNode, src, filePath)

	case *parse.RangeNode:
		return extractFromBranch(&n.BranchNode, src, filePath)

	case *parse.WithNode:
		return extractFromBranch(&n.BranchNode, src, filePath)

	case *parse.PipeNode:
		return extractFromPipe(n, src, filePath)

	default:
		return nil
	}
}

func extractFromBranch(b *parse.BranchNode, src, filePath string) []Translation {
	var result []Translation
	if b.List != nil {
		result = append(result, extractFromNode(b.List, src, filePath)...)
	}
	if b.ElseList != nil {
		result = append(result, extractFromNode(b.ElseList, src, filePath)...)
	}
	return result
}

func extractFromCommand(cmd *parse.CommandNode, src, filePath string) []Translation {
	translations := extractFromCallCommand(cmd, src, filePath)

	for _, arg := range cmd.Args {
		if pipe, ok := arg.(*parse.PipeNode); ok {
			translations = append(translations, extractFromPipe(pipe, src, filePath)...)
		}
	}

	return translations
}

func extractFromPipe(pipe *parse.PipeNode, src, filePath string) []Translation {
	return flatMap(pipe.Cmds, func(cmd *parse.CommandNode) []Translation {
		return extractFromCommand(cmd, src, filePath)
	})
}

func flatMap[T any, R any](items []T, fn func(T) []R) []R {
	var result []R
	for _, item := range items {
		result = append(result, fn(item)...)
	}
	return result
}

// Parse and extract translations from a single template file
func extractFromFile(path string) ([]Translation, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	treeSet := make(map[string]*parse.Tree)
	t := parse.New(filepath.Base(path))
	t.Mode = parse.SkipFuncCheck
	_, err = t.Parse(string(src), "", "", treeSet)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	trees := make([]*parse.Tree, 0, len(treeSet))
	for _, tree := range treeSet {
		trees = append(trees, tree)
	}
	sort.Slice(trees, func(i, j int) bool {
		return trees[i].Name < trees[j].Name
	})

	return flatMap(trees, func(tree *parse.Tree) []Translation {
		return extractFromNode(tree.Root, string(src), path)
	}), nil
}

// Combine translations with the same msgid
func mergeTranslations(allTranslations []Translation) []Translation {
	byMsgID := make(map[string]*Translation)
	for _, tr := range allTranslations {
		if existing, ok := byMsgID[tr.MsgID]; ok {
			existing.Refs = existing.Refs.Union(tr.Refs)
		} else {
			t := tr
			byMsgID[tr.MsgID] = &t
		}
	}

	result := make([]Translation, 0, len(byMsgID))
	for _, tr := range byMsgID {
		result = append(result, *tr)
	}
	slices.SortFunc(result, func(a, b Translation) int {
		return strings.Compare(a.MsgID, b.MsgID)
	})
	return result
}

func main() {
	templateGlob := flag.String("templates", "view/*.tmpl", "glob pattern for template files")
	potPath := flag.String("out", "messages.pot", "output POT file path")
	flag.Parse()

	files, err := filepath.Glob(*templateGlob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error globbing templates: %v\n", err)
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "No template files found matching %s\n", *templateGlob)
		os.Exit(1)
	}
	sort.Strings(files)

	var allTranslations []Translation
	for _, file := range files {
		trs, err := extractFromFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting from %s: %v\n", file, err)
			os.Exit(1)
		}
		allTranslations = append(allTranslations, trs...)
	}

	merged := mergeTranslations(allTranslations)

	po := gotext.NewPo()
	domain := po.GetDomain()
	domain.Headers.Add("Content-Type", "text/plain; charset=UTF-8")
	domain.Headers.Add("Plural-Forms", "nplurals=2; plural=(n != 1);")

	for _, tr := range merged {
		refs := mapset.Sorted(tr.Refs)
		if plural, ok := tr.MsgIDPlural.Get(); ok {
			po.SetN(tr.MsgID, plural, 1, "")
			po.SetN(tr.MsgID, plural, 2, "")
		} else {
			po.Set(tr.MsgID, "")
		}
		po.SetRefs(tr.MsgID, refs)
	}

	data, err := po.MarshalText()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling POT: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*potPath, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing POT file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Extracted %d translations to %s\n", len(merged), *potPath)
}
