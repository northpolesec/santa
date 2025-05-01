# Santa Documentation

The Santa documentation is published at https://northpole.dev. This folder
contains the source.

Santa's docs are published using [Docusaurus](https://docusaurus.io). Almost all
of the documentation is written in Markdown and is inside the `docs/` folder.

Changes to the documentation for Santa's configuration options will generally
be made in `src/lib/santaconfig.ts` or one of the components in
`src/components/`.

### Testing Locally

To preview changes to the site, ensure you have NodeJS installed (use homebrew)
and run:

```
$ pnpm i
$ pnpm start
```

Docusuarus will start serving on localhost, usually on port 3000. It will also
open the docs site in your browser. While the command is running any changes
you make will immediately be reflected on this local server.

