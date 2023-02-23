package com.C9group34.socialnetworkproject.service;


import com.C9group34.socialnetworkproject.dto.ConversationCreateDto;
import com.C9group34.socialnetworkproject.dto.ConversationDto;
import com.C9group34.socialnetworkproject.dto.MessageDto;
import com.C9group34.socialnetworkproject.models.Conversation;
import com.C9group34.socialnetworkproject.models.Message;
import com.C9group34.socialnetworkproject.models.Participant;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.repository.ConversationRepository;
import com.C9group34.socialnetworkproject.repository.MessageRepository;
import com.C9group34.socialnetworkproject.repository.ParticipantRepository;
import com.C9group34.socialnetworkproject.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ConversationService {

    @Autowired
    ConversationRepository conversationRepository;
    UserRepository userRepository;
    MessageRepository messageRepository;
    ParticipantRepository participantRepository;

    public List<ConversationDto> getAll(){
        List<Conversation> conversations = conversationRepository.findAll();
        return conversations.stream()
                .map(c -> mapToDTO(c))
                .collect(Collectors.toList());
    }

    public Conversation createConversation(ConversationCreateDto conversationCreateDto){
        Optional<User> creator = userRepository.findById(conversationCreateDto.getCreator());
        Optional<User> user = userRepository.findById(conversationCreateDto.getUser());

        Conversation newConversation = new Conversation(conversationCreateDto.getTitle(), creator);

        Conversation conversationCreated = conversationRepository.save(newConversation);

        //Message messageDto = new Message(conversationCreateDto.getContent(), conversationCreated, creator);

        //Participant participant1 = new Participant(conversationCreated, creator);
        //Participant participant2 = new Participant(conversationCreated, user);

        //messageRepository.save(messageDto);
        //participantRepository.save(participant1);
        //participantRepository.save(participant2);
        return conversationCreated;
    }

    private ConversationDto mapToDTO(Conversation c) {
        ConversationDto conversationDto = new ConversationDto(c.getId(), c.getTitle(), c.getUser().getId());
        return conversationDto;
    }

}
