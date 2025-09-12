function swcOptimizationPlugin(context, options) {
  return {
    name: 'swc-optimization-plugin',
    configureWebpack(config, isServer) {
      // Find and modify the existing JavaScript/TypeScript rule instead of adding a new one
      const rules = config.module.rules;
      
      // Find the rule that handles JS/TS files
      const jsRule = rules.find(rule => {
        if (rule.test && rule.test.toString().includes('jsx?')) {
          return true;
        }
        if (rule.oneOf) {
          return rule.oneOf.some(oneOfRule => 
            oneOfRule.test && oneOfRule.test.toString().includes('jsx?')
          );
        }
        return false;
      });

      if (jsRule && jsRule.oneOf) {
        // Find the specific rule for JS/TS files within oneOf
        const jsOneOfRule = jsRule.oneOf.find(rule => 
          rule.test && rule.test.toString().includes('jsx?')
        );
        
        if (jsOneOfRule && jsOneOfRule.use) {
          // Replace babel-loader with swc-loader
          const loaders = Array.isArray(jsOneOfRule.use) ? jsOneOfRule.use : [jsOneOfRule.use];
          const babelLoaderIndex = loaders.findIndex(loader => 
            (typeof loader === 'string' && loader.includes('babel-loader')) ||
            (typeof loader === 'object' && loader.loader && loader.loader.includes('babel-loader'))
          );
          
          if (babelLoaderIndex !== -1) {
            loaders[babelLoaderIndex] = {
              loader: require.resolve('swc-loader'),
              options: {
                jsc: {
                  parser: {
                    syntax: 'typescript',
                    tsx: true,
                  },
                  transform: {
                    react: {
                      runtime: 'automatic',
                    },
                  },
                  target: 'es2018',
                },
                sourceMaps: true,
              },
            };
          }
        }
      }

      return {
        resolve: {
          ...config.resolve,
        },
      };
    },
  };
}

module.exports = swcOptimizationPlugin;