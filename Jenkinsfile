// Job `desplegar`. Toda la lógica está en deploy/jenkins/desplegar.sh, que tiene
// tests; aquí solo se prepara el entorno. Parámetros (MODO, VERSION, ENSAYO) y
// disparadores en deploy/jenkins/values.yaml (JCasC). Runbook 05-jenkins.md.
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
        - {name: AWS_REGION, value: eu-south-2}
        - {name: AWS_RETRY_MODE, value: standard}
        - {name: AWS_MAX_ATTEMPTS, value: "5"}
      envFrom:
        - secretRef:
            name: jenkins-avisos
      resources:
        requests: {cpu: 100m, memory: 128Mi}
        limits: {cpu: "1", memory: 256Mi}
'''
        }
    }
    stages {
        stage('Desplegar') {
            steps {
                sh 'URL_EJECUCION="$BUILD_URL" sh deploy/jenkins/desplegar.sh'
            }
        }
    }
}
