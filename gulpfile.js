var gulp = require('gulp'),
    minifyHtml = require('gulp-minify-html'),
    templateCache = require('gulp-angular-templatecache');

gulp.task('templates-bootstrap3', function () {
    gulp.src('template/bootstrap3/**/bin-*.html')
        .pipe(minifyHtml())
        .pipe(templateCache('checkpoint-tpls-bootstrap3.js', {standalone: true, module: 'checkpoint.templates'}))
        .pipe(gulp.dest('src/main/js'));
});

gulp.task('default', ['templates-bootstrap3']);