import React, { createContext, useContext, useState, useEffect } from 'react';

const ThemeContext = createContext();

export const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'cyber-default');
  const [lighting, setLighting] = useState(() => parseFloat(localStorage.getItem('lighting')) || 1.0);

  useEffect(() => {
    localStorage.setItem('theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  useEffect(() => {
    localStorage.setItem('lighting', lighting);
    document.documentElement.style.filter = `brightness(${lighting})`;
  }, [lighting]);

  return (
    <ThemeContext.Provider value={{ theme, setTheme, lighting, setLighting }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => useContext(ThemeContext);
