# Porto Passkey Login Example with React & Vite

This project demonstrates how to implement passkey-based login for Ethereum accounts in a React application using [Porto](https://porto.com/) and [Wagmi](https://wagmi.sh/). The application is built with Vite and uses TypeScript.

## Description

This example showcases a simple frontend integration of Porto, allowing users to connect their Ethereum wallets using passkeys. It includes:

-   A React component for handling the connect/disconnect logic.
-   Wagmi configuration for interacting with Ethereum chains and the Porto connector.
-   HTTPS setup for the Vite development server, as required by Porto.

## Prerequisites

Before you begin, ensure you have the following installed:

-   [Node.js](https://nodejs.org/) (v18.x or later recommended)
-   [npm](https://www.npmjs.com/) (comes with Node.js) or [yarn](https://yarnpkg.com/)

## Getting Started

Follow these steps to set up and run the project locally:

1.  **Clone the repository (or download the source code):**
    If you are working with a local copy of the project (e.g., after `npm create vite@latest my-react-app`), you can skip this step and navigate directly into the `my-react-app` directory.
    ```bash
    # Example if cloning from a repository:
    # git clone <repository-url>
    # cd my-react-app
    ```

2.  **Navigate to the project directory:**
    Ensure your terminal is in the `my-react-app` directory.
    ```bash
    cd path/to/my-react-app
    ```

3.  **Install dependencies:**
    Install the required packages.
    ```bash
    npm install
    # or
    # yarn install
    ```

4.  **Run the development server:**
    This project uses Vite, which will start a local development server.
    ```bash
    npm run dev
    # or
    # yarn dev
    ```
    The application will be accessible at `https://localhost:5173` (or another port if 5173 is in use - check your terminal output).

## HTTPS Requirement for Porto

Porto requires a secure context (HTTPS) to function correctly, even in a local development environment. This example project handles this by:

-   Using `vite-plugin-mkcert` to automatically generate a trusted self-signed SSL certificate for `localhost`.
-   Configuring the Vite development server (`vite.config.ts`) to use HTTPS.

When you first run `npm run dev`, `vite-plugin-mkcert` might prompt you for permission to install the local CA (Certificate Authority) if it's not already installed. This is necessary for your browser to trust the local SSL certificate.

If you encounter any issues with HTTPS, ensure that the local CA provided by `mkcert` is trusted by your system and browser.

## Key Files

-   `src/App.tsx`: Main application component, sets up Wagmi providers and renders the login UI.
-   `src/components/PasskeyLogin.tsx`: React component for the passkey login button and displaying connection status.
-   `src/wagmi.ts`: Wagmi configuration, including the Porto connector setup.
-   `vite.config.ts`: Vite configuration, including the HTTPS setup with `vite-plugin-mkcert`.
-   `src/App.css`: Basic styling for the application.

This setup provides a streamlined way to develop and test Porto passkey integration locally.
