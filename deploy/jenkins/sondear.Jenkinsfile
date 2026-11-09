// Job `sondear`: mira si hay una versión nueva y, si la hay, lanza `desplegar`.
// Va aparte para que sus ejecuciones, una cada 5 minutos, no borren del historial
// las de los despliegues. `desplegar` vuelve a elegir la versión: una ejecución
// duplicada en la cola termina sin hacer nada.
pipeline {
    agent {
        kubernetes {
            inheritFrom 'default'
            defaultContainer 'herramientas'
            yaml '''
spec:
  serviceAccountName: jenkins-agente
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
  containers:
    - name: herramientas
      image: alpine/k8s:1.36.6@sha256:d9cb78be55e6e47c54e8a77bbf35ef87e98e5a03fbe5db7654d28bb78cc7d57e
      command: [sleep]
      args: [infinity]
      env:
        - {name: HOME, value: /home/jenkins/agent}
      resources:
        requests: {cpu: 50m, memory: 64Mi}
        limits: {cpu: 500m, memory: 128Mi}
'''
        }
    }
    options {
        // Con disableConcurrentBuilds, una consulta colgada bloquearía las siguientes
        timeout(time: 10, unit: 'MINUTES')
    }
    stages {
        stage('Consultar') {
            steps {
                script {
                    def version = sh(script: 'MODO=consultar sh deploy/jenkins/desplegar.sh', returnStdout: true).trim()
                    if (version) {
                        echo "Versión nueva: ${version}"
                        build job: 'desplegar', wait: false, parameters: [string(name: 'MODO', value: 'automatico')]
                    }
                }
            }
        }
    }
}
