import React, { createContext, useContext, useState, useEffect } from 'react';

interface SettingsContextType {
  useOptimisticAuth: boolean;
  setUseOptimisticAuth: (value: boolean) => void;
}

const SettingsContext = createContext<SettingsContextType | undefined>(undefined);

export const useSettings = (): SettingsContextType => {
  const context = useContext(SettingsContext);
  if (!context) {
    throw new Error('useSettings must be used within a SettingsProvider');
  }
  return context;
};

interface SettingsProviderProps {
  children: React.ReactNode;
}

export const SettingsProvider: React.FC<SettingsProviderProps> = ({ children }) => {
  const [useOptimisticAuth, setUseOptimisticAuth] = useState(() => {
    const saved = localStorage.getItem('useOptimisticAuth');
    return saved ? JSON.parse(saved) : false; // Default to synchronous mode
  });

  useEffect(() => {
    localStorage.setItem('useOptimisticAuth', JSON.stringify(useOptimisticAuth));
  }, [useOptimisticAuth]);

  return (
    <SettingsContext.Provider value={{ useOptimisticAuth, setUseOptimisticAuth }}>
      {children}
    </SettingsContext.Provider>
  );
};