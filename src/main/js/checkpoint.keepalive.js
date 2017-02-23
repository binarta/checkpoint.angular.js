angular.module("checkpoint.keepalive", ['binarta-checkpointjs-angular1', 'config', 'notifications'])
    .run(['$timeout', '$http', 'config', 'topicMessageDispatcher', 'binarta',
        function ($timeout, $http, config, topicMessageDispatcher, binarta) {
            var signedIn, timeoutPromise;

            binarta.checkpoint.profile.eventRegistry.observe({
                signedin: onSignedIn,
                signedout: onSignedOut
            });

            function onSignedIn() {
                if (!signedIn) {
                    signedIn = true;
                    keepAliveRecurring();
                }
            }

            function onSignedOut() {
                signedIn = false;
                if (timeoutPromise) $timeout.cancel(timeoutPromise);
            }

            function keepAlive(args) {
                $http.get(config.baseUri + 'api/keepalive', {
                    withCredentials: true
                }).then(function () {
                    if (args && args.onSuccess) args.onSuccess();
                }, function (error) {
                    if (error.status == 401) topicMessageDispatcher.fire('system.info', {
                        code: 'checkpoint.session.expired',
                        persistent: true
                    });
                });
            }

            function keepAliveRecurring() {
                timeoutPromise = $timeout(function () {
                    keepAlive({onSuccess: keepAliveRecurring});
                }, 1200000);
            }
        }]);