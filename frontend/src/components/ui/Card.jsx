export default function Card({ children, className = '', title, subtitle, action, padding = true }) {
  const bodyClass = padding
    ? 'relative'
    : 'relative flex min-h-0 flex-1 flex-col overflow-hidden'

  return (
    <section className={`cyber-card ${padding ? 'p-5' : ''} ${className}`}>
      {(title || action) && (
        <div className={`relative flex items-start justify-between gap-4 ${padding ? 'mb-4' : 'p-5 pb-0'}`}>
          <div>
            {title && <h2 className="text-base font-semibold cyber-text tracking-tight">{title}</h2>}
            {subtitle && <p className="text-sm muted-text mt-0.5">{subtitle}</p>}
          </div>
          {action}
        </div>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  )
}
