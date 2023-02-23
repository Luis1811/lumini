package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.models.Role;
import com.C9group34.socialnetworkproject.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/role")
public class RolesControllers {

    @Autowired
    RoleService roleService;

    @PostMapping("/new")
    @Operation(
            summary = "Create a new role",
            description = "This Endpoint is for create a new role for the social network Lumini.\n" +
                          "The properties required they are specified in the section of Schema- Roles >",
            responses = {
                    @ApiResponse(responseCode = "201",ref = "createdRC"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity createRole(@io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{ \"title\" : \"Graphic Designer\", \"description\" : \"A group of designers\" }"
                    )
            )
    ) @RequestBody Role r){
        roleService.createRole(r);
        return new ResponseEntity(r, HttpStatus.CREATED);
    }

    @GetMapping("/all")
    @Operation(
            summary = "Get all roles",
            description = "This Endpoint is for get all the roles of the social network Lumini.\n" +
                          "The properties of request is not required.",
            responses = {
                    @ApiResponse(responseCode = "201",ref = "getAllRC"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity getAll(){
        return new ResponseEntity(roleService.getAllRoles(), HttpStatus.OK);
    }
}
