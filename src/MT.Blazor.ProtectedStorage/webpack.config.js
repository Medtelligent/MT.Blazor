const path = require('path');

module.exports = (env, args) =>({
    resolve: {
        extensions: ['.js']
    },
    devtool: args.mode === 'development' ? 'inline-source-map' : false,
    module: {
        rules: [
            {
                test: /\.js$/,
                loader: 'babel-loader',
                exclude: file => (
                    /node_modules/.test(file)
                )
            }
        ]
    },
    experiments: {
        outputModule: true
    },
    entry: {
        "protectedStorageInterop": './Scripts/index.js'
    },
    output: {
        path: path.join(__dirname, '/wwwroot'),
        filename: '[name].js',
        module: true,
        libraryTarget: 'module'
    }
});
