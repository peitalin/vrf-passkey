import Porto from 'porto';

// Get DOM elements
const connectButton = document.getElementById('connectButton') as HTMLButtonElement;
const disconnectButton = document.getElementById('disconnectButton') as HTMLButtonElement;
const accountInfoDiv = document.getElementById('accountInfo') as HTMLDivElement;

// Instantiate Porto
// The .create() method might not exist or might be different based on Porto's actual API.
// Assuming Porto is a class that needs to be instantiated, or has a static create method.
// If Porto is an object with methods directly, this line might change.
// For now, following the subtask's `Porto.create()`
let porto: any; // Use 'any' for now, will adjust if Porto's types are available and different

try {
    porto = Porto.create();
} catch (error) {
    console.error("Failed to initialize Porto:", error);
    if (accountInfoDiv) {
        accountInfoDiv.textContent = "Error: Could not initialize Porto. See console for details.";
    }
    // Disable buttons if Porto fails to initialize
    if (connectButton) connectButton.disabled = true;
    if (disconnectButton) disconnectButton.disabled = true;
}

function updateUI(isConnected: boolean, message?: string) {
    if (isConnected) {
        connectButton.style.display = 'none';
        disconnectButton.style.display = 'inline-block'; // or 'block'
        accountInfoDiv.textContent = message || 'Connected';
    } else {
        connectButton.style.display = 'inline-block'; // or 'block'
        disconnectButton.style.display = 'none';
        accountInfoDiv.textContent = message || 'Not connected';
    }
}

// Initial UI state
updateUI(false);

if (porto && connectButton) {
    connectButton.addEventListener('click', async () => {
        accountInfoDiv.textContent = 'Connecting...';
        try {
            // The method 'wallet_connect' might be specific and needs to be verified from Porto docs.
            // Standard EIP-1193 is 'eth_requestAccounts'. Porto might wrap this.
            const accounts = await porto.provider.request({ method: 'eth_requestAccounts' });
            
            if (accounts && accounts.length > 0) {
                updateUI(true, `Connected: ${accounts[0]}`);
                console.log('Connected accounts:', accounts);
            } else {
                updateUI(false, 'Connection failed: No accounts returned.');
                console.warn('No accounts returned from wallet_connect');
            }
        } catch (error: any) {
            updateUI(false, `Connection error: ${error.message || error}`);
            console.error('Connection error:', error);
        }
    });
} else if (!porto && connectButton) {
    connectButton.textContent = "Porto not loaded";
    connectButton.disabled = true;
}


if (porto && disconnectButton) {
    disconnectButton.addEventListener('click', async () => {
        accountInfoDiv.textContent = 'Disconnecting...';
        try {
            // The method 'wallet_disconnect' is not a standard EIP-1193 method.
            // Porto might have its own method for this.
            // For standard EIP-1193, there isn't a direct "disconnect" method usually.
            // Applications typically clear their state.
            // Assuming Porto provides a specific disconnect method.
            // If not, we'll just clear the state.
            
            // Attempting a hypothetical disconnect method. If this isn't correct for Porto,
            // it would need to be adjusted based on Porto's API.
            // Some wallets/providers have a 'close' or similar, or expect the app to just forget the connection.
            if (typeof porto.provider.close === 'function') { // Example for some providers
                 await porto.provider.close();
            } else if (typeof porto.provider.disconnect === 'function') { // Another common example
                 await porto.provider.disconnect();
            }
            // If Porto doesn't have a specific disconnect, just update UI
            updateUI(false, 'Disconnected');
            console.log('Disconnected');

        } catch (error: any) {
            // If disconnect fails, still update UI to a disconnected-like state
            updateUI(false, `Disconnect error: ${error.message || error}. Assuming disconnected.`);
            console.error('Disconnection error:', error);
        }
    });
}

// Check initial connection status (some wallets/providers might auto-connect)
// This is a simplified check. A real app might need more robust logic.
if (porto && typeof porto.provider.isConnected === 'function' && porto.provider.isConnected()) {
    // If already connected, try to get accounts
    (async () => {
        try {
            const accounts = await porto.provider.request({ method: 'eth_accounts' });
            if (accounts && accounts.length > 0) {
                updateUI(true, `Already connected: ${accounts[0]}`);
            } else {
                updateUI(false); // Not connected or no accounts
            }
        } catch (error) {
            console.warn("Error checking initial connection status:", error);
            updateUI(false); // Assume not connected if error
        }
    })();
} else if (porto) {
    // If no isConnected method, assume not connected initially
    updateUI(false);
}
