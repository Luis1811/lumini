package com.C9group34.socialnetworkproject.repository;

import com.C9group34.socialnetworkproject.models.Conversation;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ConversationRepository extends JpaRepository<Conversation, Integer> {
}
