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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/users")
//@CrossOrigin(origins = "${host}")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/new")
    @Operation(
            summary = "Create new use",
            responses = {
                    @ApiResponse(responseCode = "201",ref = "created"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity register (@io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"name\" : \"Luis\", \"surname\" : \"Uzcategui\", \"email\" : \"luis@example.com\", \"password\" : \"123456789\", \"phone\" : \"+593979010717\" }"
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
            responses = {
                    @ApiResponse(responseCode = "200",ref = "getAll"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity retrieve(){

        return new ResponseEntity(userService.retrieveAll(), HttpStatus.OK);
    }

    @GetMapping("/{userId}")
    public ResponseEntity retrieveByIdWithFavoritePublications(@PathVariable Integer userId) {

        try {
            UserDto user = userService.retrieveByIdWithFavoritePublications(userId);
            return new ResponseEntity(user, HttpStatus.OK);
        } catch (ResourceNotFoundException e) {
            System.out.println(e.getMessage());
            return new ResponseEntity(HttpStatus.NOT_FOUND);
        }
    }

    @DeleteMapping("/{userId}")
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
