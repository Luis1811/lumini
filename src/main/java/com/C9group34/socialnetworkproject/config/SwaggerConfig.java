package com.C9group34.socialnetworkproject.config;

import com.C9group34.socialnetworkproject.util.JsonReadFileObject;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.responses.ApiResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;

import java.io.IOException;

@OpenAPIDefinition
@Configuration
/*
@SecurityScheme(
        name = "token",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        scheme = "bearer"
)*/
public class SwaggerConfig {

    /*
    @Bean
    public OpenAPI baseOpenAPI() throws IOException {

        JsonReadFileObject jsonReadFileObject = new JsonReadFileObject();

        ApiResponse created = new ApiResponse().content(
                new Content().addMediaType(MediaType.APPLICATION_JSON_VALUE,
                        new io.swagger.v3.oas.models.media.MediaType().addExamples("default",
                                new Example().value(jsonReadFileObject.read().get("created").toString())))
        ).description("User created successful");

        ApiResponse getAll = new ApiResponse().content(
                new Content().addMediaType(MediaType.APPLICATION_JSON_VALUE,
                        new io.swagger.v3.oas.models.media.MediaType().addExamples("default",
                                new Example().value(jsonReadFileObject.read().get("getAll").toString())))
        ).description("Get all users response");

        ApiResponse createdRC = new ApiResponse().content(
                new Content().addMediaType(MediaType.APPLICATION_JSON_VALUE,
                        new io.swagger.v3.oas.models.media.MediaType().addExamples("default",
                                new Example().value(jsonReadFileObject.read().get("createdRC").toString())))
        ).description("Element created successful");

        ApiResponse getAllRC = new ApiResponse().content(
                new Content().addMediaType(MediaType.APPLICATION_JSON_VALUE,
                        new io.swagger.v3.oas.models.media.MediaType().addExamples("default",
                                new Example().value(jsonReadFileObject.read().get("getAllRC").toString())))
        ).description("Get all element response");

        ApiResponse badRequest = new ApiResponse().content(
                new Content().addMediaType(MediaType.APPLICATION_JSON_VALUE,
                        new io.swagger.v3.oas.models.media.MediaType().addExamples("default",
                                new Example().value(jsonReadFileObject.read().get("badRequest").toString())))
        ).description("Bad request");

        Components components = new Components();
        components.addResponses("created",created);
        components.addResponses("getAll",getAll);
        components.addResponses("createdRC",createdRC);
        components.addResponses("getAllRC",getAllRC);
        components.addResponses("badRequest",badRequest);

        return new OpenAPI()
                .components(components)
                .info(new Info()
                        .title("Documentation Lumini")
                        .version("1.0.1")
                        .description("API rest for social media"));
    }

     */
}