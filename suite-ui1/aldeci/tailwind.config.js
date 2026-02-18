/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        // ALdeci Severity colors - FIGMA_ADVANCED_SPECS_V1
        severity: {
          critical: "hsl(var(--severity-critical))",
          high: "hsl(var(--severity-high))",
          medium: "hsl(var(--severity-medium))",
          low: "hsl(var(--severity-low))",
          info: "hsl(var(--severity-info))",
        },
        // Phase evolution colors
        phase: {
          1: "hsl(var(--phase-1))",
          2: "hsl(var(--phase-2))",
          3: "hsl(var(--phase-3))",
          4: "hsl(var(--phase-4))",
        },
        // System/connector status
        status: {
          healthy: "hsl(var(--status-healthy))",
          degraded: "hsl(var(--status-degraded))",
          failed: "hsl(var(--status-failed))",
          unknown: "hsl(var(--status-unknown))",
        },
        // Compliance framework colors
        compliance: {
          soc2: "hsl(var(--compliance-soc2))",
          iso: "hsl(var(--compliance-iso))",
          pci: "hsl(var(--compliance-pci))",
          slsa: "hsl(var(--compliance-slsa))",
        },
        // Brand colors for connectors
        brand: {
          github: "hsl(var(--brand-github))",
          snyk: "hsl(var(--brand-snyk))",
          wiz: "hsl(var(--brand-wiz))",
          aws: "hsl(var(--brand-aws))",
          azure: "hsl(var(--brand-azure))",
          gcp: "hsl(var(--brand-gcp))",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
}
