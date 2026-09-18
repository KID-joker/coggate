{
  "variables": {
    "coggate_library_path%": "<!(node -e \"const path=require('node:path');const p=process.env.COGGATE_LIBRARY_PATH||'';const expected={darwin:'libcoggate_ffi.dylib',linux:'libcoggate_ffi.so',win32:'coggate_ffi.dll'}[process.platform];if(!path.isAbsolute(p)||path.basename(p)!==expected)throw new Error('COGGATE_LIBRARY_PATH must name the coggate_ffi shared library');process.stdout.write(p)\")",
    "coggate_link_library%": "<!(node -e \"const p=process.env.COGGATE_LIBRARY_PATH||'';process.stdout.write(process.platform==='win32'&&p?p+'.lib':p)\")",
    "coggate_runtime_basename%": "<!(node -p \"require('node:path').basename(process.env.COGGATE_LIBRARY_PATH || '')\")",
    "coggate_install_name%": "<!(node -e \"const {execFileSync}=require('node:child_process');const p=process.env.COGGATE_LIBRARY_PATH||'';if(process.platform==='darwin'&&p)process.stdout.write(execFileSync('otool',['-D',p],{encoding:'utf8'}).trim().split(/\\r?\\n/).at(-1).trim())\")",
    "node_executable%": "<!(node -p \"process.execPath\")"
  },
  "targets": [{
    "target_name": "coggate",
    "sources": ["src/coggate.cc"],
    "include_dirs": ["<(module_root_dir)/../../packages/ffi/include"],
    "libraries": ["<(coggate_link_library)"],
    "defines": ["NAPI_VERSION=9"],
    "cflags_cc!": ["-fno-exceptions"],
    "cflags_cc": ["-std=c++17", "-Wall", "-Wextra", "-Wpedantic", "-Werror"],
    "conditions": [
      ["OS=='mac'", {
        "xcode_settings": {
          "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
          "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
          "OTHER_CPLUSPLUSFLAGS": ["-Wall", "-Wextra", "-Wpedantic", "-Werror"],
          "LD_RUNPATH_SEARCH_PATHS": ["@loader_path"]
        }
      }],
      ["OS=='linux'", { "ldflags": ["-Wl,-rpath,$$ORIGIN"] }],
      ["OS=='win'", {
        "msvs_settings": { "VCCLCompilerTool": {
          "ExceptionHandling": 1,
          "WarningLevel": 4,
          "TreatWarningAsError": True,
          "AdditionalOptions": ["/std:c++17"]
        }},
        "copies": [{
          "destination": "<(PRODUCT_DIR)",
          "files": ["<(coggate_library_path)"]
        }]
      }]
    ]
  }, {
    "target_name": "coggate_runtime",
    "type": "none",
    "dependencies": ["coggate"],
    "conditions": [
      ["OS=='mac'", {
        "actions": [{
          "action_name": "relocate_coggate_runtime",
          "inputs": ["<(PRODUCT_DIR)/coggate.node", "<(coggate_library_path)"],
          "outputs": [
            "<(PRODUCT_DIR)/<(coggate_runtime_basename)",
            "<(PRODUCT_DIR)/coggate.relocated.stamp"
          ],
          "action": [
            "<(node_executable)", "-e",
            "const fs=require('node:fs');const path=require('node:path');const cp=require('node:child_process');const [source,destination,oldName,addon,stamp]=process.argv.slice(1);const relocated='@rpath/'+path.basename(destination);fs.copyFileSync(source,destination);cp.execFileSync('install_name_tool',['-id',relocated,destination]);cp.execFileSync('install_name_tool',['-change',oldName,relocated,addon]);fs.writeFileSync(stamp,'');",
            "<(coggate_library_path)",
            "<(PRODUCT_DIR)/<(coggate_runtime_basename)",
            "<(coggate_install_name)",
            "<(PRODUCT_DIR)/coggate.node",
            "<(PRODUCT_DIR)/coggate.relocated.stamp"
          ]
        }]
      }],
      ["OS=='linux'", {
        "copies": [{
          "destination": "<(PRODUCT_DIR)",
          "files": ["<(coggate_library_path)"]
        }]
      }]
    ]
  }]
}
