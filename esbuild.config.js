import esbuild from "esbuild";
import { readFile } from "node:fs/promises";

// Embeds imported PNG files as a synchronous Uint8Array of raw PNG bytes.
// The emitted module decodes the base64 string at runtime via atob(), avoiding
// any async Image/TextureLoader pipeline. Useful for feeding decoded pixels
// straight into THREE.DataTexture at module-eval time.
const inlinePngBytes = {
  name: "inline-png-bytes",
  setup(build) {
    build.onLoad({ filter: /\.png$/ }, async (args) => {
      const bytes = await readFile(args.path);
      const b64 = bytes.toString("base64");
      const contents = `
const B64 = ${JSON.stringify(b64)};
export default Uint8Array.from(atob(B64), (c) => c.charCodeAt(0));
`;
      return { contents, loader: "js" };
    });
  },
};

esbuild.build({
  entryPoints: ["ts/main.ts"],
  outfile: "public/bundle.js",
  bundle: true,
  minify: true,
  target: "es6",
  format: "esm",
  plugins: [inlinePngBytes],
});
