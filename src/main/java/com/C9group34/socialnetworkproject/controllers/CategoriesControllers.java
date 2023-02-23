package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.models.Category;
import com.C9group34.socialnetworkproject.service.CategoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/categories")
public class CategoriesControllers {

    @Autowired
    CategoryService categoryService;

    @PostMapping("/create")
    @Operation(
            summary = "Create a new category",
            description = "This Endpoint is for create a new category for the social network Lumini.\n" +
                          "The properties required they are specified in the section of Schema- Category >",
            responses = {
                    @ApiResponse(responseCode = "201",ref = "createdRC"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity create(@io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"title\" : \"Illustrations\", \"description\" : \"Pictures illustrations\" }"
                    )
            )
    ) @RequestBody Category c){
        return new ResponseEntity(categoryService.create(c), HttpStatus.CREATED);
    }

    @GetMapping("/all")
    @Operation(
            summary = "Get all categories",
            description = "This Endpoint is for get all the categories of the social network Lumini.\n" +
                          "The properties of request is not required.",
            responses = {
                    @ApiResponse(responseCode = "201",ref = "getAllRC"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity getAll(){
        return new ResponseEntity(categoryService.getAll(), HttpStatus.OK);
    }


}
