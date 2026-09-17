/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        severity: {
          high: "#ef4444",
          medium: "#f97316",
          low: "#eab308",
        },
      },
    },
  },
  plugins: [],
}
