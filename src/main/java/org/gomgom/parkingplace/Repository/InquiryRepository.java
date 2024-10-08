package org.gomgom.parkingplace.Repository;

import org.gomgom.parkingplace.Entity.Inquiry;
import org.gomgom.parkingplace.Entity.ParkingLot;
import org.gomgom.parkingplace.Entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface InquiryRepository extends JpaRepository<Inquiry, Long> {
    /**
     * 작성자: 오지수
     * 2024.09.12 : parkingLot으로 문의 목록 불러오기
     * @param parkingLot
     * @param pageable
     * @return Page로 문의 반환
     */
    Page<Inquiry> findByParkingLot(ParkingLot parkingLot, Pageable pageable);

    /**
     * 작성자: 오지수
     * 2024.09.20 : user로 문의 목록 불러오기
     * @param user
     * @param pageable
     * @return Page로 문의 반환
     */
    Page<Inquiry> findByUser(User user, Pageable pageable);

    /**
     * 작성자: 오지수
     * 2024.09.21: 주차장 관리자 페이지에서 전체 목록 불러오기
     * @param parkingLot
     * @param from
     * @param to
     * @param pageable
     * @return
     */
    Page<Inquiry> findByParkingLotAndInquiryCreatedAtGreaterThanEqualAndInquiryCreatedAtLessThan(ParkingLot parkingLot, LocalDateTime from, LocalDateTime to, Pageable pageable);

    /**
     * 작성자: 오지수
     * 2024.09.21: 주차장 관리자 페이지에서 미답변 문의 목록 불러오기
     * @param parkingLot
     * @param from
     * @param to
     * @param pageable
     * @return
     */
    Page<Inquiry> findByParkingLotAndAnswerCreatedAtIsNullAndInquiryCreatedAtGreaterThanEqualAndInquiryCreatedAtLessThan(ParkingLot parkingLot, LocalDateTime from, LocalDateTime to, Pageable pageable);

    /**
     * 작성자: 오지수
     * 2024.09.21: 주차장 관리자 페이지에서 답변완료 문의 목록 불러오기
     * @param parkingLot
     * @param from
     * @param to
     * @param pageable
     * @return
     */
    Page<Inquiry> findByParkingLotAndAnswerCreatedAtIsNotNullAndInquiryCreatedAtGreaterThanEqualAndInquiryCreatedAtLessThan(ParkingLot parkingLot, LocalDateTime from, LocalDateTime to, Pageable pageable);
}
