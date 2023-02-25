package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.models.Conversation;
import com.C9group34.socialnetworkproject.service.ConversationService;
import org.hibernate.mapping.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/conversations")
public class ConversationsControllers {
    @Autowired
    ConversationService conversationService;

    /*
    @GetMapping("/all")
    public ResponseEntity getAllConversations(){
        return new ResponseEntity(conversationService.getAll(), HttpStatus.OK);
    }

*/
}
