import { http, createConfig, createStorage } from 'wagmi'
import { mainnet, sepolia } from 'wagmi/chains'
import { porto } from 'porto/wagmi'

export const config = createConfig({
  chains: [mainnet, sepolia],
  connectors: [
    porto({
      options: {
        name: 'Passkey Example App',
        url: window.location.origin,
        description: 'An example app demonstrating Porto passkey authentication',
        icon: `${window.location.origin}/favicon.ico`,
        debug: true, // Enable debug logging
      },
    }),
  ],
  storage: createStorage({ storage: localStorage }),
  transports: {
    [mainnet.id]: http(),
    [sepolia.id]: http(),
  },
})