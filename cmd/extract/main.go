package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
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

// Extract translations from a Go source file by finding Tr/TrN sentinel calls.
func extractFromGoFile(path string) ([]Translation, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var translations []Translation
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name != "Tr" && ident.Name != "TrN" {
			return true
		}

		pos := fset.Position(call.Pos())
		loc := fmt.Sprintf("%s:%d", path, pos.Line)

		if len(call.Args) < 1 {
			fmt.Fprintf(os.Stderr, "Warning: %s: %s call with no arguments, skipping\n", loc, ident.Name)
			return true
		}

		msgid, ok := stringLiteral(call.Args[0])
		if !ok {
			fmt.Fprintf(os.Stderr, "Warning: %s: %s call with non-string-literal msgid, skipping\n", loc, ident.Name)
			return true
		}

		var msgidPlural mo.Option[string]
		if ident.Name == "TrN" {
			if len(call.Args) < 2 {
				fmt.Fprintf(os.Stderr, "Warning: %s: TrN call missing plural argument, skipping\n", loc)
				return true
			}
			plural, ok := stringLiteral(call.Args[1])
			if !ok {
				fmt.Fprintf(os.Stderr, "Warning: %s: TrN call with non-string-literal msgid_plural, skipping\n", loc)
				return true
			}
			msgidPlural = mo.Some(plural)
		}

		translations = append(translations, Translation{
			MsgID:       msgid,
			MsgIDPlural: msgidPlural,
			Refs:        mapset.NewSet(loc),
		})
		return true
	})

	return translations, nil
}

// stringLiteral extracts a string value from an *ast.BasicLit if it is a string token.
func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
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
	potPath := flag.String("out", "messages.pot", "output POT file path")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: extract [flags] <file1> [file2] ...")
		os.Exit(1)
	}

	var templateFiles, goFiles []string
	for _, arg := range args {
		if strings.HasSuffix(arg, ".tmpl") {
			templateFiles = append(templateFiles, arg)
		} else if strings.HasSuffix(arg, ".go") && !strings.HasSuffix(arg, "_test.go") {
			goFiles = append(goFiles, arg)
		}
	}

	var allTranslations []Translation

	for _, file := range templateFiles {
		trs, err := extractFromFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting from %s: %v\n", file, err)
			os.Exit(1)
		}
		allTranslations = append(allTranslations, trs...)
	}

	for _, file := range goFiles {
		trs, err := extractFromGoFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting from %s: %v\n", file, err)
			os.Exit(1)
		}
		allTranslations = append(allTranslations, trs...)
	}

	merged := mergeTranslations(allTranslations)

	var buf bytes.Buffer
	buf.WriteString(`msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\n"
"Plural-Forms: nplurals=2; plural=(n != 1);\n"
`)

	for _, tr := range merged {
		refs := mapset.Sorted(tr.Refs)
		buf.WriteString("\n")
		if len(refs) > 0 {
			buf.WriteString("#: " + strings.Join(refs, " ") + "\n")
		}
		msgid := gotext.EscapeSpecialCharacters(tr.MsgID)
		if plural, ok := tr.MsgIDPlural.Get(); ok {
			buf.WriteString("msgid \"" + msgid + "\"\n")
			buf.WriteString("msgid_plural \"" + gotext.EscapeSpecialCharacters(plural) + "\"\n")
			buf.WriteString("msgstr[0] \"\"\n")
			buf.WriteString("msgstr[1] \"\"\n")
		} else {
			buf.WriteString("msgid \"" + msgid + "\"\n")
			buf.WriteString("msgstr \"\"\n")
		}
	}

	if err := os.WriteFile(*potPath, buf.Bytes(), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing POT file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Extracted %d translations to %s\n", len(merged), *potPath)
}
