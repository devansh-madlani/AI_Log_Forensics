// Small inline icon set (stroke icons, 24px grid) so the dashboard needs
// no icon-library dependency. Icons are decorative by default; pass a
// `label` to expose one to assistive technology.
const PATHS = {
  collect: <><path d="M12 3v12" /><path d="m7 10 5 5 5-5" /><path d="M5 21h14" /></>,
  flask: <><path d="M9 3h6" /><path d="M10 3v6L4.5 18.5A1.7 1.7 0 0 0 6 21h12a1.7 1.7 0 0 0 1.5-2.5L14 9V3" /><path d="M7.5 15h9" /></>,
  analyze: <><circle cx="11" cy="11" r="6.5" /><path d="m20 20-4.2-4.2" /><path d="M8.5 11h5" /><path d="M11 8.5v5" /></>,
  search: <><circle cx="11" cy="11" r="6.5" /><path d="m20 20-4.2-4.2" /></>,
  close: <><path d="M6 6l12 12" /><path d="M18 6 6 18" /></>,
  chevron: <path d="m9 6 6 6-6 6" />,
  chevronDown: <path d="m6 9 6 6 6-6" />,
  sliders: <><path d="M4 7h10" /><path d="M18 7h2" /><circle cx="16" cy="7" r="2" /><path d="M4 17h4" /><path d="M12 17h8" /><circle cx="10" cy="17" r="2" /></>,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  alert: <><path d="M12 4 2.5 20h19L12 4Z" /><path d="M12 10v4.5" /><path d="M12 17.5v.01" /></>,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v5" /><path d="M12 8v.01" /></>,
  shield: <><path d="M12 3 5 6v5.5c0 4.4 3 8 7 9.5 4-1.5 7-5.1 7-9.5V6l-7-3Z" /><path d="m9 12 2 2 4-4" /></>,
  windows: <><path d="M3.5 5.5 10.5 4.5v7h-7z" /><path d="M13 4.1 20.5 3v8.5H13z" /><path d="M3.5 12.5h7v7l-7-1z" /><path d="M13 12.5h7.5V21L13 19.9z" /></>,
  apple: <><path d="M16.4 12.6c0-2.3 1.9-3.4 2-3.5-1.1-1.6-2.8-1.8-3.4-1.8-1.4-.2-2.8.9-3.5.9-.7 0-1.9-.8-3.1-.8-1.6 0-3.1.9-3.9 2.4-1.7 2.9-.4 7.2 1.2 9.6.8 1.1 1.7 2.4 3 2.4 1.2 0 1.6-.8 3.1-.8s1.8.8 3.1.8c1.3 0 2.1-1.2 2.9-2.3.9-1.3 1.3-2.6 1.3-2.7 0 0-2.6-1-2.7-4.2Z" /><path d="M14.2 5.5c.6-.8 1.1-1.9 1-3-1 .1-2.1.7-2.8 1.5-.6.7-1.1 1.8-1 2.9 1.1.1 2.1-.6 2.8-1.4Z" /></>,
  linux: <><path d="M12 3c-2.2 0-3.3 1.9-3.3 4.2 0 1.6-.6 2.6-1.6 4-1.1 1.5-2.1 3.3-2.1 5.3 0 1.2.6 2 1.6 2.4" /><path d="M12 3c2.2 0 3.3 1.9 3.3 4.2 0 1.6.6 2.6 1.6 4 1.1 1.5 2.1 3.3 2.1 5.3 0 1.2-.6 2-1.6 2.4" /><path d="M7 20.5c1.3.4 2.8-.4 3.2-1.4h3.6c.4 1 1.9 1.8 3.2 1.4" /><circle cx="10.4" cy="7.5" r=".6" /><circle cx="13.6" cy="7.5" r=".6" /><path d="M10.8 10h2.4l-1.2 1z" /></>,
  layers: <><path d="m12 3 9 5-9 5-9-5 9-5Z" /><path d="m3 13 9 5 9-5" /></>,
  beaker: <><path d="M6 3h12" /><path d="M8 3v5l-4 9.5A2 2 0 0 0 5.8 20h12.4a2 2 0 0 0 1.8-2.5L16 8V3" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  file: <><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5" /></>,
  cpu: <><rect x="6" y="6" width="12" height="12" rx="2" /><path d="M9.5 9.5h5v5h-5z" /><path d="M9 2.5V6M15 2.5V6M9 18v3.5M15 18v3.5M2.5 9H6M2.5 15H6M18 9h3.5M18 15h3.5" /></>,
  sparkle: <path d="M12 3.5 13.8 10.2 20.5 12l-6.7 1.8L12 20.5l-1.8-6.7L3.5 12l6.7-1.8z" />,
};

export default function Icon({ name, size = 16, label, className = '', strokeWidth = 1.8 }) {
  const content = PATHS[name];
  if (!content) return null;
  return (
    <svg
      className={`icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      focusable="false"
    >
      {content}
    </svg>
  );
}
