import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";
import docusaurusPluginLLMs from "docusaurus-plugin-llms/src";

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: "Santa",
  tagline: "",
  favicon: "img/favicon.ico",

  // Set the production url of your site here
  url: "https://northpole.dev",
  // Set the /<baseUrl>/ pathname under which your site is served
  baseUrl: "/",

  trailingSlash: true,

  // GitHub pages deployment config.
  organizationName: "northpolesec",
  projectName: "santa",

  onBrokenLinks: "throw",
  onBrokenMarkdownLinks: "warn",

  // Analytics scripts
  scripts: [
    "https://plausible.io/js/pa-XQGVabe4SD4KoYNvIp588.js",
    "/plausible.js",
  ],

  markdown: {
    mermaid: true,
  },

  themes: ["@docusaurus/theme-mermaid"],

  plugins: [
    ["./src/plugins/tailwind.config.js", {}],
    [
      "@docusaurus/plugin-client-redirects",
      {
        fromExtensions: ["html", "htm"],
        redirects: [
          // Redirects from the old Jekyll-based docs
          {
            to: "/configuration/keys",
            from: "/deployment/configuration.html",
          },
          {
            to: "/features/sync",
            from: [
              "/introduction/syncing-overview.html",
              "/deployment/sync-servers.html",
              "/development/sync-protocol.html",
            ],
          },
          {
            to: "/features/stats",
            from: "/deployment/stats.html",
          },
          {
            to: "/features/faa",
            from: "/deployment/file-access-auth.html",
          },
          {
            to: "/features/binary-authorization#scope",
            from: "/concepts/scopes.html",
          },
          {
            to: "/features/binary-authorization#client-mode",
            from: "/concepts/mode.html",
          },
        ],
      },
    ],
    [
      docusaurusPluginLLMs,
      {
        title: "Santa Documentation",
        description:
          "Documentation for Santa, a binary and file access authorization system for macOS from North Pole Security",
        generateLLMsTxt: true,
        generateLLMsFullTxt: true,
        docsDir: "docs",
        excludeImports: true,
        removeDuplicateHeadings: true,
        generateMarkdownFiles: true,
      },
    ],
    [
      "@docusaurus/plugin-google-gtag",
      {
        trackingID: "G-NRVWHNDHFK",
        anonymizeIP: true,
      },
    ],
  ],

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  presets: [
    [
      "classic",
      {
        docs: {
          routeBasePath: "/", // Serve the docs at the site's root
          sidebarPath: "./sidebars.ts",
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: "https://github.com/northpolesec/santa/tree/main/docs",
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: "light",
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },

    announcementBar: {
      id: "workshop_announcement",
      content:
        '<a href="https://northpole.security" class="no-underline"><span class="announcement-bar-prefix">Allowlisting that doesn\'t break business: </span>Manage Santa with <span class="underline">Workshop</span><span class="announcement-bar-suffix">, the official sync server from North Pole Security</span></a>',
      backgroundColor: "#FF5050",
      textColor: "#ffffff",
      isCloseable: true,
    },

    navbar: {
      logo: {
        alt: "Santa by North Pole Security",
        src: "/img/santa-black.svg",
        srcDark: "/img/santa-white.svg",
        height: 50,
        width: 176,
      },
      items: [
        {
          href: "https://github.com/northpolesec/santa",
          className: "header-github-link",
          "aria-label": "GitHub",
          position: "right",
        },
      ],
    },

    footer: {
      links: [
        {
          label: "North Pole Security",
          href: "https://northpole.security",
        },
        {
          label: "GitHub",
          href: "https://github.com/northpolesec/santa",
        },
        {
          label: "MacAdmins Slack",
          href: "https://macadmins.slack.com/archives/C0E1VRBGW",
        },
        {
          label: "Bluesky",
          href: "https://bsky.app/profile/northpolesec.bsky.social",
        },
        {
          label: "X",
          href: "https://x.com/northpolesec",
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} North Pole Security, Inc.`,
    },

    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["bash"],
    },

    algolia: {
      appId: "5Z70AHS23I",
      // This key is safe to expose.
      apiKey: "4c12177dbe87a2a9d03f4be3b421c7ae",
      indexName: "northpole",
      contextualSearch: true,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
