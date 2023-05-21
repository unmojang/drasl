import esbuild from "esbuild";
import inlineImage from "esbuild-plugin-inline-image";

esbuild.build({
	entryPoints: ["js/main.ts"],
	outfile: "public/bundle.js",
	bundle: true,
	minify: true,
	target: "es6",
	format: "esm",
	plugins: [
		inlineImage({ limit: -1, })
	],
});
