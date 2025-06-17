// Test setup with necessary polyfills and mocks for WebAuthn testing
import { TextEncoder, TextDecoder } from 'util';
import 'jest-environment-jsdom';

// Polyfill Node.js globals for browser APIs
Object.assign(global, {
  TextEncoder,
  TextDecoder,
});

// Polyfill atob/btoa for base64 operations
if (typeof global.atob === 'undefined') {
  global.atob = (str: string) => Buffer.from(str, 'base64').toString('binary');
}

if (typeof global.btoa === 'undefined') {
  global.btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');
}

// Mock crypto.getRandomValues
Object.defineProperty(global, 'crypto', {
  value: {
    getRandomValues: jest.fn((array: any) => {
      for (let i = 0; i < array.length; i++) {
        array[i] = Math.floor(Math.random() * 256);
      }
      return array;
    }),
    randomUUID: jest.fn(() => '12345678-1234-5678-9abc-123456789012'),
  },
});

// Mock fetch globally
global.fetch = jest.fn();

// Mock navigator.credentials for WebAuthn testing
Object.defineProperty(global, 'navigator', {
  value: {
    credentials: {
      create: jest.fn(),
      get: jest.fn(),
    },
  },
  writable: true,
});

// Mock window object and location
Object.defineProperty(global, 'window', {
  value: {
    location: {
      hostname: 'localhost',
      origin: 'http://localhost:3000',
    },
    isSecureContext: true,
  },
  writable: true,
});

// Mock indexedDB
const mockIDBRequest = {
  onsuccess: null,
  onerror: null,
  result: null,
  error: null,
};

const mockIDBDatabase = {
  transaction: jest.fn(() => ({
    objectStore: jest.fn(() => ({
      get: jest.fn(() => mockIDBRequest),
      put: jest.fn(() => mockIDBRequest),
      delete: jest.fn(() => mockIDBRequest),
      clear: jest.fn(() => mockIDBRequest),
      getAll: jest.fn(() => mockIDBRequest),
      index: jest.fn(() => ({
        getAll: jest.fn(() => mockIDBRequest),
      })),
    })),
  })),
  createObjectStore: jest.fn(() => ({
    createIndex: jest.fn(),
  })),
  close: jest.fn(),
  objectStoreNames: {
    contains: jest.fn(() => false),
  },
};

Object.defineProperty(global, 'indexedDB', {
  value: {
    open: jest.fn(() => ({
      ...mockIDBRequest,
      onupgradeneeded: null,
      onblocked: null,
      onblocking: null,
      result: mockIDBDatabase,
    })),
  },
});

console.log('Test setup loaded with polyfills');