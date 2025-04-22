Please build the project using Gradle.

After building, move the generated .jar file to the /opt/keycloak/providers directory.

Below is an example of how to run it using docker-compose:

```pgsql
keycloak-project/
├── modules/
│   └── naver-keycloak-identity-provider.jar
└── docker-compose.yml
```


``` yml
services:
    keycloak:
        image: quay.io/keycloak/keycloak:latest
        container_name: keycloak-container
        command: start-dev
        environment:
            - KC_BOOTSTRAP_ADMIN_USERNAME=admin
            - KC_BOOTSTRAP_ADMIN_PASSWORD=admin
        volumes:
            - ./modules:/opt/keycloak/providers
        ports:
            - "8080:8080"
```

Make sure the modules directory contains the correctly built .jar file before starting the container.

[Reference](https://subji.github.io/posts/2020/07/24/keycloak4)

