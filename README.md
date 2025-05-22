# Simple Porto Passkey Login Example (TypeScript + esbuild)

This project *intends* to demonstrate a basic implementation of passkey-based login for Ethereum accounts using [Porto](https://porto.com/) with vanilla TypeScript and [esbuild](https://esbuild.github.io/) for bundling and serving.

## Project Structure

The main files in this example are:

-   `index.html`: The main HTML file that loads the application and provides the UI elements.
-   `src/main.ts`: The TypeScript entry point where the Porto logic (connection, disconnection, UI updates) is implemented.
-   `style.css`: Basic CSS for styling the HTML elements.
-   `package.json`: Defines project metadata, dependencies (`porto`, `ethers`), devDependencies (`typescript`, `esbuild`), and npm scripts.
-   `tsconfig.json`: Configuration file for the TypeScript compiler.

## Intended Usage / Setup Instructions

1.  **Install Dependencies:**
    Open your terminal in the project root and run:
    ```bash
    npm install
    ```
    This command *should* install all necessary dependencies listed in `package.json`.

2.  **Build the Application:**
    To bundle the TypeScript code into a JavaScript file that can be run in the browser, use:
    ```bash
    npm run build
    ```
    This script uses `esbuild` to compile `src/main.ts` and outputs the bundle to `dist/main.js`.

3.  **Serve the Application:**
    To start a local development server, run:
    ```bash
    npm run serve
    ```
    This script uses `esbuild`'s built-in server to serve the project files. It also includes a `--watch` flag to automatically rebuild when source files change.
    Once the server is running (typically it will indicate a local address like `http://localhost:8000`), open `index.html` in your browser via this server address.

## Known Issues / Environment Limitations

**Critical Dependency Installation Failure:**

In the current testing environment, the `npm install` command does not appear to correctly install dependencies (such as `porto`, `ethers`, and even the `esbuild` devDependency) into the `node_modules` directory. While `npm install` often completes without reporting fatal errors, subsequent checks reveal that the package directories within `node_modules` are missing or empty.

**Impact:**

This fundamental installation issue prevents the example from functioning:
-   `npm run build` will fail because `esbuild` cannot resolve the `porto` import (as `porto` is not actually present in `node_modules`). If `esbuild` itself is also not correctly installed, `npx esbuild` might attempt to download it, but the core bundling issue with `porto` would persist.
-   `npm run serve` will similarly fail, either because `esbuild` isn't found or because it cannot perform the initial build due to the missing `porto` dependency.

The code provided in `src/main.ts`, `index.html`, and `package.json` represents a standard setup for this type of vanilla TypeScript and esbuild application. However, due to these environment-specific dependency installation problems, the example **could not be fully tested or run** as intended.

## Porto and HTTPS

For the optimal user experience, especially when using its iframe mode, Porto requires a secure context (HTTPS). The `esbuild` serve command used in this example (`npx esbuild src/main.ts --bundle --outfile=dist/main.js --servedir=. --platform=browser --watch`) defaults to serving over HTTP.

If this example were fully runnable and deployed, or if `esbuild`'s server were configured for HTTPS (which typically requires providing a certificate and key), Porto would be able to operate in its iframe mode. Over HTTP, Porto would likely fall back to using pop-up windows for its operations, which might be a less seamless experience. This aspect could not be verified due to the aforementioned dependency issues.
