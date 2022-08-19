const path = require('path');

module.exports = (env, args) =>({
    resolve: {
        extensions: ['.ts', '.js']
    },
    devtool: args.mode === 'development' ? 'inline-source-map' : false,
    module: {
        rules: [
            {
                test: /\.ts?$/,
                loader: 'ts-loader'
            }
        ]
    },
    experiments: {
        outputModule: true
    },
    entry: {
        "indexedDbInterop": './Scripts/index.ts'
    },
    output: {
        path: path.join(__dirname, '/wwwroot'),
        filename: '[name].js',
        module: true,
        libraryTarget: 'module'
    }
});
