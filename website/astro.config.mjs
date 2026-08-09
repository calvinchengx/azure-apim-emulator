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
            { slug: '01-charter-and-parity' },
            { slug: '02-architecture' },
          ],
        },
        {
          label: 'The product surface',
          items: [
            { slug: '03-management-plane' },
            { slug: '04-gateway-and-protocols' },
            { slug: '05-policy-and-expressions' },
            { slug: '06-portal-workspaces-platform' },
            { slug: '07-identity-networking-observability' },
          ],
        },
        {
          label: 'Verification',
          items: [
            { slug: '08-testing-and-sdk-matrix' },
            { slug: 'generated/service-schema-2024-05-01' },
          ],
        },
        {
          label: 'Project',
          items: [
            { slug: '09-roadmap' },
            { slug: '10-risk-register' },
            { slug: '11-clean-room-grounding' },
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
