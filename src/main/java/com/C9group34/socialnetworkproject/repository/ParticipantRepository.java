package com.C9group34.socialnetworkproject.repository;

import com.C9group34.socialnetworkproject.models.Participant;
import com.C9group34.socialnetworkproject.models.User;
import jakarta.persistence.CascadeType;
import jakarta.persistence.OneToMany;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ParticipantRepository extends JpaRepository<Participant, Integer> {


}
