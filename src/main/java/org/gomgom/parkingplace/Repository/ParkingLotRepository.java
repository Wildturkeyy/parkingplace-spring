package org.gomgom.parkingplace.Repository;


import org.gomgom.parkingplace.Dto.ParkingLotDto;
import org.gomgom.parkingplace.Entity.ParkingLot;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/**
 * @Author 김경민
 * @date 2024-09-04
 *
 */
public interface ParkingLotRepository extends JpaRepository<ParkingLot, Long> {

    @Query("SELECT new org.gomgom.parkingplace.Dto.ParkingLotDto$ParkingLotMarkerDto(pl)" +
            "FROM ParkingLot pl " +
            "WHERE pl.latitude BETWEEN :minLat AND :maxLat " +
            "AND pl.longitude BETWEEN :minLon AND :maxLon")
    List<ParkingLotDto.ParkingLotMarkerDto> getParkingLots(
            @Param("minLat") double minLat,
            @Param("maxLat") double maxLat,
            @Param("minLon") double minLon,
            @Param("maxLon") double maxLon);
}
