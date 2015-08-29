var gulp = require('gulp'),
    minifyHtml = require('gulp-minify-html'),
    template = require('gulp-template'),
    templateCache = require('gulp-angular-templatecache');

var minifyHtmlOpts = {
    empty: true,
    cdata: true,
    conditionals: true,
    spare: true,
    quotes: true
};

gulp.task('templates-bootstrap3', function () {
    gulp.src('template/bootstrap3/bin-*.html')
        .pipe(template({shop: false}))
        .pipe(minifyHtml(minifyHtmlOpts))
        .pipe(templateCache('checkpoint-tpls-bootstrap3.js', {standalone: true, module: 'checkpoint.templates'}))
        .pipe(gulp.dest('src/main/js'));
});

gulp.task('templates-shop-bootstrap3', function () {
    gulp.src('template/bootstrap3/bin-*.html')
        .pipe(template({shop: true}))
        .pipe(minifyHtml(minifyHtmlOpts))
        .pipe(templateCache('checkpoint-shop-tpls-bootstrap3.js', {standalone: true, module: 'checkpoint.templates'}))
        .pipe(gulp.dest('src/main/js'));
});

gulp.task('default', ['templates-bootstrap3', 'templates-shop-bootstrap3']);