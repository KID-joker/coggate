# CogGate Node.js SDK

The native Node.js SDK exposes the synchronous CogGate challenge service through Node-API 9.

Set `COGGATE_LIBRARY_PATH` to the absolute path of the platform `coggate_ffi` shared library,
then build and test the package with Node.js 22 or newer:

```sh
npm run build
npm test
npm run example
```

The example prints `verify: accepted` after exercising the real native addon.
