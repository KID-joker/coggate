{
  "variables": {
    "agentgate_include_dir%": "<!(node -p \"process.env.AGENTGATE_INCLUDE_DIR || ''\")",
    "agentgate_library%": "<!(node -p \"process.env.AGENTGATE_LIBRARY || ''\")",
    "agentgate_runtime_library%": "<!(node -p \"process.env.AGENTGATE_RUNTIME_LIBRARY || ''\")",
    "agentgate_static%": "<!(node -p \"process.env.AGENTGATE_STATIC || '0'\")",
    "agentgate_runtime_source%": "<!(node -p \"process.env.AGENTGATE_RUNTIME_LIBRARY || process.env.AGENTGATE_LIBRARY || ''\")",
    "agentgate_runtime_basename%": "<!(node -p \"require('node:path').basename(process.env.AGENTGATE_RUNTIME_LIBRARY || process.env.AGENTGATE_LIBRARY || '')\")",
    "agentgate_install_name%": "<!(node -e \"const {execFileSync}=require('node:child_process');const p=process.env.AGENTGATE_LIBRARY||'';if(process.platform==='darwin'&&p)process.stdout.write(execFileSync('otool',['-D',p],{encoding:'utf8'}).trim().split(/\\r?\\n/).at(-1).trim())\")",
    "node_executable%": "<!(node -p \"process.execPath\")"
  },
  "targets": [{
    "target_name": "agentgate",
    "sources": ["src/addon.cc"],
    "include_dirs": ["<(agentgate_include_dir)"],
    "libraries": ["<(agentgate_library)"],
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
      ["agentgate_static=='1'", { "defines": ["AGENTGATE_STATIC"] }],
      ["OS=='win' and agentgate_runtime_library!=''", {
        "msvs_settings": { "VCCLCompilerTool": {
          "AdditionalOptions": ["/std:c++17", "/W4", "/WX"]
        }},
        "copies": [{
          "destination": "<(PRODUCT_DIR)",
          "files": ["<(agentgate_runtime_library)"]
        }]
      }]
    ]
  }, {
    "target_name": "agentgate_runtime",
    "type": "none",
    "dependencies": ["agentgate"],
    "conditions": [
      ["OS=='mac' and agentgate_static!='1'", {
        "actions": [{
          "action_name": "relocate_agentgate_runtime",
          "inputs": ["<(PRODUCT_DIR)/agentgate.node", "<(agentgate_runtime_source)"],
          "outputs": [
            "<(PRODUCT_DIR)/<(agentgate_runtime_basename)",
            "<(PRODUCT_DIR)/agentgate.relocated.stamp"
          ],
          "action": [
            "<(node_executable)", "-e",
            "const fs=require('node:fs');const path=require('node:path');const cp=require('node:child_process');const [source,destination,oldName,addon,stamp]=process.argv.slice(1);const relocated='@rpath/'+path.basename(destination);fs.copyFileSync(source,destination);cp.execFileSync('install_name_tool',['-id',relocated,destination]);cp.execFileSync('install_name_tool',['-change',oldName,relocated,addon]);fs.writeFileSync(stamp,'');",
            "<(agentgate_runtime_source)",
            "<(PRODUCT_DIR)/<(agentgate_runtime_basename)",
            "<(agentgate_install_name)",
            "<(PRODUCT_DIR)/agentgate.node",
            "<(PRODUCT_DIR)/agentgate.relocated.stamp"
          ]
        }]
      }],
      ["OS=='linux' and agentgate_static!='1'", {
        "copies": [{
          "destination": "<(PRODUCT_DIR)",
          "files": ["<(agentgate_runtime_source)"]
        }]
      }]
    ]
  }]
}
