pipeline {
  agent {
    docker {
      image 'docker.io/python:3'
    }
  }
  stages {
    stage('Preparation') {
      steps {
        withEnv(["HOME=${env.WORKSPACE}"]) {
	  sh 'pip install --user -r requirements.txt'
	}
      }
    }
    stage ('Build') {
      steps {
        sh 'python3 setup.py build'
      }
    }
    stage ('Test') {
      steps {
        withEnv(["HOME=${env.WORKSPACE}"]) {
          sh 'python3 setup.py test'
	}
      }
    }
  }
}
