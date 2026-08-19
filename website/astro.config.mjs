import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { remarkMermaid } from './plugins/remark-mermaid.mjs';

// Project GitHub Pages site: https://calvinchengx.github.io/azure-apim-emulator/
export default defineConfig({
  site: 'https://calvinchengx.github.io',
  base: '/azure-apim-emulator/',
  // remarkMermaid turns ```mermaid fences into <pre class="mermaid"> before
  // Expressive Code sees them; src/components/Head.astro renders them client-side.
  markdown: {
    remarkPlugins: [remarkMermaid],
  },
  integrations: [
    starlight({
      title: 'Azure APIM Emulator',
      components: {
        Head: './src/components/Head.astro',
        // Top nav: the parity version picker, rendered beside the search box.
      },
      description:
        'A local emulator of the Azure API Management data plane — secrets, keys, and certificates — with real challenge-based authentication against entra-emulator.',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/calvinchengx/azure-apim-emulator' },
      ],
      editLink: {
        baseUrl: 'https://github.com/calvinchengx/azure-apim-emulator/edit/main/docs/',
      },
      // Mirrors mkdocs.yml's nav, which this replaces. The numbered files are
      // the design chapters; parity.md is the live ledger they are measured
      // against, so it gets its own group rather than being buried in Project.
      sidebar: [
        {
          label: 'Start here',
          items: [
            { slug: 'index' },
            { slug: '01-quickstart' },
            { slug: '02-installation' },
            { slug: '04-configuration' },
          ],
        },
        {
          label: 'How it is built',
          items: [
            { slug: '00-charter-and-parity' },
            { slug: '03-architecture' },
          ],
        },
        {
          label: 'The product surface',
          items: [
            { slug: '05-management-plane' },
            { slug: '06-gateway-and-protocols' },
            { slug: '07-policy-and-expressions' },
            { slug: '08-portal-workspaces-platform' },
            { slug: '09-identity-networking-observability' },
          ],
        },
        {
          label: 'Verification',
          items: [
            { slug: '10-testing-and-sdk-matrix' },
            { slug: 'generated/service-schema-2024-05-01' },
          ],
        },
        {
          label: 'Project',
          items: [
            { slug: '11-roadmap' },
            { slug: '12-risk-register' },
            { slug: '13-clean-room-grounding' },
          ],
        },
        {
          label: 'Parity',
          items: [
            { slug: 'parity', label: 'Parity ledger' },
          ],
        },
      ],
    }),
  ],
});
