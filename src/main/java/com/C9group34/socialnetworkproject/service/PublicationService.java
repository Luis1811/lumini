package com.C9group34.socialnetworkproject.service;


import com.C9group34.socialnetworkproject.dto.PublicationDto;
import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.models.Publication;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.repository.PublicationRepository;
import com.C9group34.socialnetworkproject.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class PublicationService {

    /*
    private final PublicationRepository publicationRepository;
    private final UserRepository userRepository;
    private final UserService userService;*/

    // ------------cambio por autowired por simplicidad de codigo---------------
    @Autowired
    private  PublicationRepository publicationRepository;
    @Autowired
    private  UserRepository userRepository;
    /*
    @Autowired
    private  UserService userService;*/


    public void create(PublicationDto publicationDTO, Integer userId) {
        Optional<User> user = userRepository.findById(userId);
        Publication publication = mapToEntity(publicationDTO, user.get());
        publicationRepository.save(publication);
    }


    public List<PublicationDto> retrieveAll(Integer userId) throws ResourceNotFoundException {
        Optional<User> user = userRepository.findById(userId);
        if (user.isEmpty()) {
            throw new ResourceNotFoundException("El id del usuario que está ingresando no existe.");
        }
        List<Publication> publications = publicationRepository.findAll();
        return publications.stream()
                .map(publication -> mapToDTO(publication))
                .collect(Collectors.toList());
    }

    public PublicationDto retrieveById(Integer publicationId) throws ResourceNotFoundException {
        Optional<Publication> publication = publicationRepository.findById(publicationId);

        if (publication.isEmpty()) {
            throw new ResourceNotFoundException("El id de la publicacion que está buscando no existe.");
        }

        return mapToDTO(publication.get());
    }


    public void delete(Integer publicationId) throws ResourceNotFoundException {
        try {
            publicationRepository.deleteById(publicationId);
        } catch (EmptyResultDataAccessException e) {
            throw new ResourceNotFoundException();
        }
    }

    public void replace(Integer userId, Integer publicationID , PublicationDto publicationDto) throws ResourceNotFoundException {
        Optional<User> user = userRepository.findById(userId);
        if (user.isEmpty()) {
            throw new ResourceNotFoundException("El id del usuario que está ingresando no existe.");
        }

        Optional<Publication> publication = publicationRepository.findById(userId);
        if (publication.isEmpty()) {
            throw new ResourceNotFoundException("El id de la publicacion que está ingresando no existe.");
        }

        Publication updatedPublication;
        Publication publicationToReplace = publication.get();
        updatedPublication = new Publication().builder().id(publicationToReplace.getId())
                .title(publicationDto.getTitle())
                .description(publicationToReplace.getDescription())
                .urlImg(publicationDto.getUrlImg())
                .rating(publicationDto.getRating())
                .status(publicationDto.getStatus()).build();

        publicationRepository.save(updatedPublication);

    }

    public void modify(Integer userId, Integer publicationId, Map<String, Object> fieldsToModify) throws ResourceNotFoundException {
        Optional<User> user = userRepository.findById(userId);
        if (user.isEmpty()) {
            throw new ResourceNotFoundException();
        }

        Optional<Publication> publication = publicationRepository.findById(publicationId);
        if (publication.isEmpty()) {
            throw new ResourceNotFoundException();
        }
        Publication publicationToModify = publication.get();
        fieldsToModify.forEach((key, value) -> publicationToModify.modifyAttributeValue(key, value));
        publicationRepository.save(publicationToModify);
    }

   private Publication mapToEntity(PublicationDto publicationDto , User user) {
        Publication publication = new Publication().builder().id(publicationDto.getId())
                .title(publicationDto.getTitle())
                .description(publicationDto.getDescription())
                .urlImg(publicationDto.getUrlImg())
                .rating(publicationDto.getRating())
                .status(publicationDto.getStatus())
                .user(user).build();

        return publication;
    }


    private PublicationDto mapToDTO(Publication publication) {
        PublicationDto.PublicationDtoBuilder publicationDto = new PublicationDto().builder().id(publication.getId())
                .title(publication.getTitle())
                .description(publication.getDescription())
                .urlImg(publication.getUrlImg())
                .rating(publication.getRating())
                .status(publication.getStatus());

        return publicationDto.build();
    }


}
