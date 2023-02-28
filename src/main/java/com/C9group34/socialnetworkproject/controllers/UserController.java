package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/users")
@CrossOrigin
public class UserController {

    @Autowired
    private UserService userService;


    @PostMapping("/new")
    @Operation(
            summary = "Create new use",
            description = "With endpoint can you created a new user",
            responses = {
                    @ApiResponse(responseCode = "201",ref = "created"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity register (@io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"name\" : \"Luis\", \"surname\" : \"Uzcategui\", \"email\" : \"luis@example.com\", \"password\" : \"123456789\", \"phone\" : \"+593979010717\", \"img_profile\" : \"URL\" }"
                    )
            )
    ) @RequestBody UserDto u){

        User user = null;
        try {
            user = userService.register(u);
        } catch (ExistingResourceException e) {
            System.out.println(e.getMessage());
            return new ResponseEntity(HttpStatus.NOT_IMPLEMENTED);
        }

        return new ResponseEntity(user, HttpStatus.CREATED);

    }

    @GetMapping("/all")
    @Operation(
            summary = "Get all users",
            description = "This endpoint is for get all users",
            responses = {
                    @ApiResponse(responseCode = "200",ref = "getAll"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity retrieve(){

        return new ResponseEntity(userService.retrieveAll(), HttpStatus.OK);
    }

    @GetMapping("{userId}")
    @Operation(
            summary = "Get user by ID",
            description = "With this endpoint can you get to a user by ID",
            responses = {
                    @ApiResponse(responseCode = "200",ref = "user"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity retrieveById(@PathVariable Integer userId){

        try {
            UserDto user = userService.retrieveById(userId);
            return new ResponseEntity(user, HttpStatus.OK);
        } catch (ResourceNotFoundException e) {
            System.out.println(e.getMessage());
            return new ResponseEntity("el usuario no ha sido encontrado", HttpStatus.NOT_FOUND);
        }
    }

    @DeleteMapping("/{userId}")
    @Operation(
            summary = "Delete a user",
            description = "This endpoint is for delete a user",
            responses = {
                    @ApiResponse(responseCode = "200",ref = "userDeleted"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity delete(@PathVariable Integer userId) {
        try {
            userService.delete(userId);
        } catch (ResourceNotFoundException e) {
            System.out.println(e.getMessage());
            return new ResponseEntity(HttpStatus.NOT_FOUND);
        }

        return new ResponseEntity(HttpStatus.OK);
    }

    @PutMapping("/{userId}")
    @Operation(
            summary = "Update a user",
            description = "This endpoint is for update a user"
    )
    public ResponseEntity replace(@PathVariable Integer userId,@io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"name\" : \"String\", \"surname\" : \"String\", \"email\" : \"String\", \"password\" : \"String\", \"phone\" : \"String\", \"ratings\" : 0.0 }"
                    )
            )
    ) @RequestBody UserDto user) {
        try {
            userService.replace(userId, user);
        } catch (ResourceNotFoundException e) {
            System.out.println(e.getMessage());
            return new ResponseEntity(HttpStatus.NOT_MODIFIED);
        }
        return new ResponseEntity(HttpStatus.OK);
    }

    // no usado
    /*
    @PatchMapping("/{userId}")
    public void modify(@PathVariable Integer userId,
                                 @RequestBody Map<String, Object> fieldsToModify) {
        fieldsToModify.entrySet().stream()
                .forEach(entry -> {
                    String key = entry.getKey();
                    Object value = entry.getValue();
                    Class<?> valueType = value.getClass();
                    String valueContent = String.valueOf(value); // convert value to string

                    // do something with key, valueType, and valueContent
                    System.out.println("Key: " + key + ", Type: " + valueType.getName() + ", Content: " + valueContent);
                });
        /*
        try {
            userService.modify(userId, fieldsToModify);
        } catch (ResourceNotFoundException e) {
            System.out.println(e.getMessage());
            return new ResponseEntity(HttpStatus.NOT_IMPLEMENTED);
        }

        return new ResponseEntity(HttpStatus.OK);

       }*/
}
