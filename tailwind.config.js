/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/main/resources/static/**/*.html",
    "./src/main/resources/static/**/*.js"
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        vault: {
          50: "#f0fdfa",
          500: "#14b8a6",
          900: "#042f2e",
          950: "#021817"
        }
      },
      keyframes: {
        "pulse-slow": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.5" }
        }
      },
      animation: {
        "pulse-slow": "pulse-slow 3s cubic-bezier(0.4, 0, 0.6, 1) infinite"
      }
    }
  },
  plugins: []
};
