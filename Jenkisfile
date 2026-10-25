pipeline {
    agent any

    environment {
        JAVA_HOME = '/usr/lib/jvm/java-21-openjdk-amd64'
        PATH = "${JAVA_HOME}/bin:${env.PATH}"
        IMAGE_NAME = 'microservice-gateway'
        DEPLOY_DIR = '/opt/microservices/gateway-service'
    }

    stages {

        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Test') {
            steps {
                sh 'java -version'
                sh 'mvn -version'
                sh 'mvn test -B'
            }
            post {
                always {
                    junit 'target/surefire-reports/*.xml'
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t $IMAGE_NAME:latest -t $IMAGE_NAME:$BUILD_NUMBER .'
            }
        }

        stage('Deploy') {
            steps {
                sh '''
                    # Crear el directorio si no existe (Buena práctica)
                    mkdir -p $DEPLOY_DIR

                    # Copiar archivos de configuracion al servidor
                    cp docker-compose.yml $DEPLOY_DIR/docker-compose.yml
                    cp nginx.conf         $DEPLOY_DIR/nginx.conf

                    # Levantar/actualizar contenedores
                    cd $DEPLOY_DIR
                    # 2. Actualizamos el nombre del contenedor principal aquí:
                    docker compose up -d --no-deps gateway-service
                    docker compose up -d --no-deps nginx

                    # Limpiar imagenes viejas para no llenar el EC2
                    docker image prune -f
                '''
            }
        }
    }

    post {
        failure { echo 'Pipeline del gateway-service falló' }
        success { echo 'gateway-service desplegado exitosamente' }
    }
}