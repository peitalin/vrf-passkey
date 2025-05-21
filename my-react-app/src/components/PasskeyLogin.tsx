import { useAccount, useConnect, useDisconnect } from 'wagmi'
import { porto } from 'wagmi/connectors'

export function PasskeyLogin() {
  const { address, isConnected } = useAccount()
  const { connect } = useConnect()
  const { disconnect } = useDisconnect()

  if (isConnected) {
    return (
      <div>
        <p>Connected as: {address}</p>
        <button onClick={() => disconnect()}>Disconnect</button>
      </div>
    )
  }

  return (
    <button onClick={() => connect({ connector: porto() })}>
      Connect
    </button>
  )
}
