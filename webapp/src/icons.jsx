import React from 'react'

const S = (p) => (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor"
       strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{p.children}</svg>
)

export const IcoGauge = () => <S><path d="M12 15l3.5-3.5M20 12a8 8 0 1 1-16 0 8 8 0 0 1 16 0z" /></S>
export const IcoTarget = () => <S><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4.5" /><circle cx="12" cy="12" r="0.6" fill="currentColor" /></S>
export const IcoScan = () => <S><path d="M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3zM15 15h6v6h-6z" /><path d="M12 7V4.5M12 19.5V17M7 12H4.5M19.5 12H17" /></S>
export const IcoFindings = () => <S><path d="M9 11l3 3L22 4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" /></S>
export const IcoEngine = () => <S><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7 7.5h.01M7 16.5h.01" /></S>
export const IcoOut = () => <S><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="M16 17l5-5-5-5M21 12H9" /></S>
export const IcoPlus = () => <S><path d="M12 5v14M5 12h14" /></S>
export const IcoPlay = () => <S><path d="M6 4l14 8-14 8z" /></S>
export const IcoStop = () => <S><rect x="6" y="6" width="12" height="12" rx="2" /></S>
export const IcoDoc = () => <S><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6" /></S>
export const IcoClose = () => <S><path d="M18 6L6 18M6 6l12 12" /></S>
export const IcoChev = () => <S><path d="M9 18l6-6-6-6" /></S>
export const IcoLogo = () => (
  <svg width="34" height="34" viewBox="0 0 64 64" aria-hidden="true">
    <defs>
      <linearGradient id="vlg" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stopColor="#2f8fff" /><stop offset="1" stopColor="#0073ff" />
      </linearGradient>
    </defs>
    <path fill="url(#vlg)" d="M32 4 8 16v16c0 15 10 26 24 30 14-4 24-15 24-30V16z" />
    <path fill="rgba(255,255,255,.92)" d="M32 18l-9 20h7l2-7 2 7h7z" />
  </svg>
)