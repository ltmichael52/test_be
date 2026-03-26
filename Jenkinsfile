pipeline {
    agent any

    environment {
        DOCKER_REPO = "lemichael52"
        IMAGE_TAG = "${BUILD_NUMBER}"

        DOCKER_CREDENTIALS = "docker-hub"

        KUBECONFIG_CREDENTIALS = "k3s-kubeconfig"
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Detect Changes') {
            steps {
                script {
                    CHANGED_FILES = sh(
                        script: "git diff --name-only HEAD~1 HEAD",
                        returnStdout: true
                    ).trim()

                    echo "Changed files: ${CHANGED_FILES}"
                }
            }
        }

        stage('Docker Login') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: "${DOCKER_CREDENTIALS}",
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    sh '''
                    echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
                    '''
                }
            }
        }

        stage('Setup Kubeconfig') {
            steps {
                withCredentials([file(credentialsId: "${KUBECONFIG_CREDENTIALS}", variable: 'KUBECONFIG_FILE')]) {
                    sh '''
                    mkdir -p /var/lib/jenkins/.kube
                    cp $KUBECONFIG_FILE /var/lib/jenkins/.kube/config
                    chmod 600 /var/lib/jenkins/.kube/config

                    export KUBECONFIG=/var/lib/jenkins/.kube/config
                    kubectl get nodes
                    '''
                }
            }
        }

        // ================= SERVICES =================

        stage('Build & Deploy Auth Service') {
            when {
                expression { CHANGED_FILES.contains("services/auth-service") }
            }
            steps {
                sh """
                docker build -t $DOCKER_REPO/auth-service:$IMAGE_TAG ./services/auth-service
                docker push $DOCKER_REPO/auth-service:$IMAGE_TAG

                kubectl set image deployment/auth-service \
                auth-service=$DOCKER_REPO/auth-service:$IMAGE_TAG

                kubectl rollout status deployment/auth-service
                """
            }
        }

        stage('Build & Deploy Admin Service') {
            when {
                expression { CHANGED_FILES.contains("services/admin-service") }
            }
            steps {
                sh """
                docker build -t $DOCKER_REPO/admin-service:$IMAGE_TAG ./services/admin-service
                docker push $DOCKER_REPO/admin-service:$IMAGE_TAG

                kubectl set image deployment/admin-service \
                admin-service=$DOCKER_REPO/admin-service:$IMAGE_TAG

                kubectl rollout status deployment/admin-service
                """
            }
        }

        stage('Build & Deploy Catalog Service') {
            when {
                expression { CHANGED_FILES.contains("services/catalog-service") }
            }
            steps {
                sh """
                docker build -t $DOCKER_REPO/catalog-service:$IMAGE_TAG ./services/catalog-service
                docker push $DOCKER_REPO/catalog-service:$IMAGE_TAG

                kubectl set image deployment/catalog-service \
                catalog-service=$DOCKER_REPO/catalog-service:$IMAGE_TAG

                kubectl rollout status deployment/catalog-service
                """
            }
        }

        stage('Build & Deploy Chat Service') {
            when {
                expression { CHANGED_FILES.contains("services/chat-service") }
            }
            steps {
                sh """
                docker build -t $DOCKER_REPO/chat-service:$IMAGE_TAG ./services/chat-service
                docker push $DOCKER_REPO/chat-service:$IMAGE_TAG

                kubectl set image deployment/chat-service \
                chat-service=$DOCKER_REPO/chat-service:$IMAGE_TAG

                kubectl rollout status deployment/chat-service
                """
            }
        }
    }
}