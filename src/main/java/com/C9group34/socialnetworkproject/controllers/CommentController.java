package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.CommentDto;
import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.models.Comment;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.service.CommentService;
import com.C9group34.socialnetworkproject.service.UserService;
import com.C9group34.socialnetworkproject.util.JWTutil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/comments")
@CrossOrigin
public class CommentController {
    
}
