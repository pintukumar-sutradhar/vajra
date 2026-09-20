import React, { useId } from 'react'

const S = ({ duotone, children, ...rest }) => {
  const gid = 'vg' + useId().replace(/[^a-zA-Z0-9]/g, '')
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor"
         strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...rest}>
      {duotone && (
        <defs>
          <linearGradient id={gid} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#f0abfc" />
            <stop offset="1" stopColor="#7c3aed" />
          </linearGradient>
        </defs>
      )}
      {duotone ? <g stroke={`url(#${gid})`}>{children}</g> : children}
    </svg>
  )
}

export const IcoGauge = () => <S duotone><path d="M20 12a8 8 0 1 1-16 0 8 8 0 0 1 16 0z" /><path d="M12 15l3.2-3.2M12 8v7M15.5 8.5" /></S>
export const IcoTarget = () => <S duotone><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4.5" /><circle cx="12" cy="12" r="0.6" fill="currentColor" /></S>
export const IcoScan = () => <S duotone><path d="M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3zM15 15h6v6h-6z" /><path d="M12 7V4.5M12 19.5V17M7 12H4.5M19.5 12H17" /></S>
export const IcoFindings = () => <S duotone><path d="M9 11l3 3L22 4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" /></S>
export const IcoEngine = () => <S duotone><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7 7.5h.01M7 16.5h.01" /></S>
export const IcoOut = () => <S duotone><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="M16 17l5-5-5-5M21 12H9" /></S>
export const IcoPlus = () => <S><path d="M12 5v14M5 12h14" /></S>
export const IcoRefreshCw = () => <S><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" /><path d="M21 12a9 9 0 1 1-9 9 9.75 9.75 0 0 1 6.74-2.74L21 16" /></S>
export const IcoUpload = () => <S><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" y1="3" x2="12" y2="15" /></S>
export const IcoPlay = () => <S><path d="M6 4l14 8-14 8z" /></S>
export const IcoPause = () => <S><path d="M9 4v16M15 4v16" /></S>
export const IcoStop = () => <S><rect x="6" y="6" width="12" height="12" rx="2" /></S>
export const IcoDownload = () => <S><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></S>
export const IcoShield = () => <S duotone><path d="M12 3l7 3v6c0 5-3 8-7 9-4-1-7-4-7-9V6z" /><path d="M9 12l2 2 4-4" /></S>
export const IcoFilter = () => <S><path d="M3 5h18M7 12h10M10 19h4" /></S>
export const IcoDoc = () => <S duotone><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6" /></S>
export const IcoClose = () => <S><path d="M18 6L6 18M6 6l12 12" /></S>
export const IcoChev = () => <S><path d="M9 18l6-6-6-6" /></S>
export const IcoLogo = () => (
  <svg width="34" height="34" viewBox="0 0 64 64" aria-hidden="true">
    <defs>
      <linearGradient id="vlg" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stopColor="#e9d5ff" /><stop offset="0.55" stopColor="#a78bfa" /><stop offset="1" stopColor="#7c3aed" />
      </linearGradient>
    </defs>
    <path fill="url(#vlg)" d="M32 4 8 16v16c0 15 10 26 24 30 14-4 24-15 24-30V16z" />
    <path fill="rgba(13,11,30,.92)" d="M32 18l-4 9h5.5v9h7v-9l2.5-9z" opacity="0" />
    <path fill="rgba(13,11,30,.95)" d="M32 17.5 24 35h6l1.5-6.5L33 35h6z" />
  </svg>
)