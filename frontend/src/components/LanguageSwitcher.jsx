import React, { useState, useEffect } from 'react';

// Language options: English, Hindi, and Kannada
const languages = [
  { code: 'en', name: 'English' },
  { code: 'hi', name: 'हिंदी' },
  { code: 'kn', name: 'ಕನ್ನಡ' },
];

function LanguageSwitcher() {
  const [currentLanguage, setCurrentLanguage] = useState('en');
  const [isOpen, setIsOpen] = useState(false);
  const [hoveredIndex, setHoveredIndex] = useState(null);
  const [isButtonHovered, setIsButtonHovered] = useState(false);

  useEffect(() => {
    // Prevent Google Translate banner and body displacement
    const style = document.createElement('style');
    style.textContent = `
      .goog-te-banner-frame { display: none !important; }
      body { top: 0 !important; }
      .notranslate { white-space: nowrap !important; }
    `;
    document.head.appendChild(style);

    // Check if Google Translate script is already loaded
    if (!document.querySelector('script[src*="translate.google.com"]')) {
      // Create hidden div for Google Translate
      const translateDiv = document.createElement('div');
      translateDiv.id = 'google_translate_element';
      translateDiv.style.display = 'none';
      document.body.appendChild(translateDiv);

      // Initialize Google Translate
      window.googleTranslateElementInit = () => {
        new window.google.translate.TranslateElement({
          pageLanguage: 'en',
          includedLanguages: 'en,hi,kn',
          autoDisplay: false,
        }, 'google_translate_element');
      };

      // Load Google Translate script
      const script = document.createElement('script');
      script.src = '//translate.google.com/translate_a/element.js?cb=googleTranslateElementInit';
      script.async = true;
      document.head.appendChild(script);
    }

    // Load saved language preference
    const savedLanguage = localStorage.getItem('selectedLanguage');
    if (savedLanguage) {
      setCurrentLanguage(savedLanguage);
    }
  }, []);

  const handleLanguageChange = (langCode) => {
    // Save selected language
    localStorage.setItem('selectedLanguage', langCode);
    setCurrentLanguage(langCode);
    setIsOpen(false);

    if (langCode === 'en') {
      // Clear translation cookies to return to English
      document.cookie = 'googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      document.cookie = `googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=.${window.location.hostname};`;
    } else {
      // Set translation cookies
      document.cookie = `googtrans=/en/${langCode}`;
      document.cookie = `googtrans=/en/${langCode}; path=/; domain=.${window.location.hostname}`;
    }

    // Reload page to apply translation
    window.location.reload();
  };

  const currentLangName = languages.find((lang) => lang.code === currentLanguage)?.name || 'Language';

  const containerStyle = {
    position: 'relative',
    display: 'inline-block'
  };

  const buttonStyle = {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    color: isButtonHovered ? '#fff' : '#93c5fd',
    background: isButtonHovered ? 'rgba(59, 130, 246, 0.2)' : 'none',
    border: 'none',
    cursor: 'pointer',
    padding: '0.5rem',
    borderRadius: '0.25rem',
    transition: 'all 0.2s ease',
    fontSize: '1rem',
    fontWeight: '500'
  };

  const iconStyle = {
    width: '16px',
    height: '16px'
  };

  const dropdownStyle = {
    position: 'absolute',
    top: 'calc(100% + 0.5rem)',
    right: '0',
    background: 'rgba(15, 23, 42, 0.95)',
    backdropFilter: 'blur(10px)',
    border: '1px solid rgba(59, 130, 246, 0.3)',
    borderRadius: '0.5rem',
    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.3)',
    minWidth: '150px',
    zIndex: 1000,
    overflow: 'hidden'
  };

  const getItemStyle = (index, isActive) => ({
    display: 'block',
    width: '100%',
    padding: '0.75rem 1rem',
    background: isActive ? 'rgba(59, 130, 246, 0.3)' : (hoveredIndex === index ? 'rgba(59, 130, 246, 0.2)' : 'none'),
    border: 'none',
    textAlign: 'left',
    color: (isActive || hoveredIndex === index) ? '#fff' : '#93c5fd',
    fontSize: '1rem',
    cursor: 'pointer',
    transition: 'all 0.2s ease',
    fontWeight: isActive ? '600' : '500'
  });

  return (
    <div style={containerStyle}>
      <button
        type="button"
        style={buttonStyle}
        onClick={() => setIsOpen(!isOpen)}
        onMouseEnter={() => setIsButtonHovered(true)}
        onMouseLeave={() => setIsButtonHovered(false)}
      >
        <svg
          style={iconStyle}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <circle cx="12" cy="12" r="10" />
          <line x1="2" y1="12" x2="22" y2="12" />
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
        {currentLangName}
      </button>

      {isOpen && (
        <div style={dropdownStyle}>
          {languages.map((lang, index) => (
            <button
              key={lang.code}
              type="button"
              style={getItemStyle(index, lang.code === currentLanguage)}
              onClick={() => handleLanguageChange(lang.code)}
              onMouseEnter={() => setHoveredIndex(index)}
              onMouseLeave={() => setHoveredIndex(null)}
            >
              {lang.name}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default LanguageSwitcher;