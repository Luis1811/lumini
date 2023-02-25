package com.C9group34.socialnetworkproject.service;

import org.springframework.stereotype.Service;

@Service
public class ConversationService {

    /*
    @Autowired
    ConversationRepository conversationRepository;
    UserRepository userRepository;
    MessageRepository messageRepository;
    ParticipantRepository participantRepository;

    public List<ConversationDto> getAll(){
        List<Conversation> conversations = conversationRepository.findAll();
        return conversations.stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    public Conversation createConversation(ConversationCreateDto conversationCreateDto){
        Optional<User> creator = userRepository.findById(conversationCreateDto.getCreator());
        Optional<User> user = userRepository.findById(conversationCreateDto.getUser());

        Conversation newConversation = new Conversation(conversationCreateDto.getTitle(), creator);
        Conversation conversationCreated = conversationRepository.save(newConversation);

        Message messageDto = new Message(conversationCreateDto.getContent(), conversationCreated, creator.get());

        Participant participant1 = new Participant(conversationCreated, creator.get());
        Participant participant2 = new Participant(conversationCreated, user.get());

        messageRepository.save(messageDto);
        participantRepository.save(participant1);
        participantRepository.save(participant2);
        return conversationCreated;
    }

    private ConversationDto mapToDTO(Conversation c) {
        ConversationDto conversationDto = new ConversationDto(c.getId(), c.getTitle(), c.getUser().getId());
        return conversationDto;
    }*/

}
