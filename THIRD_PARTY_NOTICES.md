# Third-Party Notices

This project vendors several third-party JavaScript libraries under `frontend/vendor/` to enable fully offline use.

These third-party components are **not** authored by the project author, and are distributed under their respective licenses.

## React
- Files: `frontend/vendor/react.production.min.js`
- Upstream: https://github.com/facebook/react
- License: MIT

## ReactDOM
- Files: `frontend/vendor/react-dom.production.min.js`
- Upstream: https://github.com/facebook/react
- License: MIT

## Babel (Standalone)
- Files: `frontend/vendor/babel.min.js`
- Upstream: https://github.com/babel/babel
- License: MIT
- Notes: This bundle includes `regenerator-runtime` (MIT).

## Tailwind CSS (runtime bundle)
- Files: `frontend/vendor/tailwindcss.js`
- Upstream: https://github.com/tailwindlabs/tailwindcss
- License: MIT
- Notes: This runtime bundle may include additional third-party components; see in-file notices.

## Framer Motion
- Files: `frontend/vendor/framer-motion.js`
- Upstream: https://github.com/framer/motion
- License: MIT
- Notes: The vendored build may not include a preserved license header.
